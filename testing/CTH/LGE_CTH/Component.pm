package LGE_CTH::Component;

use strict;
use warnings;
use Carp qw(carp croak cluck confess);

use LGE_CTH ":util";

#
# "virtual" base class
# keeps track of its users and dependencies,
# and notifies its users if something hapens here
# 


#{{{1# INTERFACE

   our %ClassData = (
   	# DO NOT TOUCH _* fields in derived classes!
	_id => {},

	# DEFINE in derived classes:
	# override with an ARRAY ref of possible states
	states => undef,
	config_template => undef,

	# DEFINE in derived classes:

	# FIXME write some documentation :-]
   );
	
   sub new;               # by magic all new Components come up in the
                          # '__UNDEF__' state.

   # query state
   sub id;
   sub as_string;         # "id: status"
   sub status;            # get the current state
	                  # internally also used to set the new state
   sub does_dependend_on; # (some component)
   sub events;            # returns list of possible events

   sub depends_on;        # (other component, callback argument)

   # debug
   sub Dump;      # Dump object data in some "readable" form
   sub say;       # print, tagged with $obj->id

#{{{2# IMPLEMENTATION

sub id     {        $_[0]->{_id} }

sub may_fail {
	my $me = shift;
	my $fail = $me->{_config}->{may_fail}||0;
	ref $fail ? $$fail : $fail;
}

sub events {
	my $me = shift;
	return () if $me->{_busy} or ! $me->takes_events;
	my $events = $me->_class_data('events');
	grep { ! $me->_compare_states($events->{$_}) } keys %$events;
}

sub as_string {
	my $me = shift;
	my $s = $me->id .": ". __dump_hash($me->status);
	$s .= " MAY FAIL" if $me->may_fail;
	$s .= " busy: $me->{_busy}" if exists $me->{_busy} and $me->{_busy};
	$s .= " current node: $me->{_current_node}->{_config}->{hostname}"
		if exists $me->{_current_node} and $me->{_current_node};
	$s;
}

# (me[,new status[,additional args for propagation]])
# the transition "events" call this with their name,
# (me,new status,event name)
sub status {
	my ($me,$new_status,$event,$event_done) = @_;
	my $class = ref $me;

	if (defined $new_status and not $me->_compare_states($new_status)) {
		$new_status  = { status => $new_status }
			if not ref $new_status eq 'HASH';

		$event_done ||= "";

		$me->say("-=> " . __dump_hash($new_status)." (".($event||"none").", $event_done)",
			join " ", caller ) if $::LGE_IS_DEBUGGING;

		# to the real world,
		# only propagate the actual event,
		# not some reactions
		if (defined $event and not $event_done) {
			if ($me->{_busy}) {
				$me->say("Don't touch me while I am busy ($me->{_busy})!");
				return undef;
			}

			return undef if $me->_generic_event($event,$new_status);
			$me->say("nothing to do for $event !??\n");
		}

		my $changed = 0;
		# for some reason, and just in case, we need to reset
		# the iterator of %$new_status ...
		keys %$new_status;
		while (my ($aspect,$value) = each %$new_status) {
			next if defined $me->{_status}->{$aspect}
			     and $me->{_status}->{$aspect} eq $new_status->{$aspect};
			$me->{_status}->{$aspect} = $new_status->{$aspect};
			$changed++;
		}
		# FIXME something like:
		# ++$me->{_states}->{$status}; # per object statistics
		# ++$possible->{$status};        # per class  statistics

		$me->_propagate_state_change($event ||= '__SET__')
			if $changed;
	}
	# ->{_status} is a ref, return a copy of it.
	# I don't want to modify the status by accident!
	return wantarray ? { %{$me->{_status}} } : $me;
}

sub _next_id {
	my $class = shift;
	(my $name = $class) =~ s/^[^:]+::([^:]+).*?$/$1/;
	no strict "refs";
	return sprintf("$name-%03d", ++$ClassData{_id}->{$class});
}

sub new {
	my ($me) = shift;
	my $class = ref $me || $me;
	croak "Don't use " . __PACKAGE__ ."::new directly\n"
		if $class eq __PACKAGE__;
	$me = {
		_id     => $class->_next_id(),

		_busy   => 0, # new_state if real world event pending

	      # _status => # current status, see below

		_config => {},
		_deps   => {},  # whom do I depend on
		_users  => {},  # who depends on me
		_refcnt  => 0,

		# statistic counts of states and events
		_states => {},
		_events => {},
	};
	bless $me, $class;

	$me->_init_config(shift || {});
	carp  "Extra arguments to new() IGNORED!\n"
		if @_;

	my $class_data = $me->_class_data;
	croak "You need to define ${class}::takes_events()!\n"
		unless $me->can('takes_events');

	$me->_register_event_methods
		unless exists $class_data->{_statistics}->{events};

	for (keys %{$class_data->{_possible_states}}) {
		$me->{_status}->{$_} = '__UNDEF__';
	}

	# should die() if they think something went wrong... 
	for (qw(CheckConfig Initialize)) { $me->$_ if $me->can($_) }

	push @LGE_CTH::ALL_OBJ, $me;
	push @LGE_CTH::EVENT_OBJ,$me if keys %{$class_data->{events}};
	my $base_class = $class;
	$base_class =~ s/^(LGE_CTH::[^:]+).*/$1/;
	no strict "refs";
	push @$base_class, $me;
	return $me;
}

sub Dump {
	my $me = shift;
	my $s = __dump ($me,0) . " = {\n";
	while (my ($k,$v) = each %$me) {
		$s .= "\t'$k' => ".__dump($v,1).",\n";
	}
	$s .= "}\n";
	return $s;
}

sub say {
	my $me = shift;
	my $id = $me->id||"";
	my $msg = join " ", @_;
	# squeeze, just in case
	$msg =~ s/^\s*(.*?)\s*$/$1/gs;
	$msg =~ s/^/$id> /gm;
	$msg .= "\n" unless $msg =~ /\n$/;
	print mytimestr . " " . $msg;
	Log($msg);
}

sub does_dependend_on {
	my ($me,$obj) = @_;
	confess "$obj not a " . __PACKAGE__ ."!\n"
		unless $obj->isa(__PACKAGE__);
	return exists $me->{_deps}->{$obj->id};
}

sub depends_on {
	my ($me,$obj,$args) = @_;
	my $this_class  = ref $me;
	my $other_class = ref $obj;

	croak (($obj||'undef') . " not a " . __PACKAGE__ ."!\n")
		unless ref($obj)
		and $obj->isa(__PACKAGE__);

	return $me if $me->does_dependend_on($obj);

	$other_class =~ s/^[^:]+::([^:]+).*?$/$1/;
	my $method = "${other_class}_changed";

	croak "$this_class wants notification from $other_class, "
	     ."but ${this_class}::$method not implemented!\n"
		unless defined $me->can($method);

	$obj->_register_user($me,defined $args ? $args : '');
	$me->{_deps}->{$obj->id} = $obj;
	return $me;
}

# purists look elsewhere; perl magic ahead.
sub _class_data {
	my ($me,$key) = @_;
	( my $class_data = ref $me ) =~ s/^([^:]+::[^:]+).*?$/::$1::ClassData/;
	no strict "refs";
	# croak "\$${class_data}{$key} does not exist!\n"
	# 	unless exists $class_data->{$key};
	return defined $key ? $class_data->{$key} : \%$class_data;
}

# helper, not method
# XXX maybe we can use Class::Struct for this...
# But actually we don't need the accessors, we don't modify the
# config, it is more the mandatory and optional arguments to the
# constructor that counts. So we cannot use Class::Struct directly.
#     
sub __hash_assign_with_template {
	# because of recursive eval {} below
	local ($SIG{__WARN__},$SIG{__DIE__});
	my ($to,$from,$template) = @_;
	die "HASH refs expected!\n"
		unless ref $to       eq 'HASH'
		and    ref $from     eq 'HASH'
		and    ref $template eq 'HASH';

	my %seen = ();
	while (my ($k,$default) = each %$template) {
		if (ref $default eq 'HASH') {
			eval {
				__hash_assign_with_template(
					$to->{$k}||={},
					$from->{$k}||={},
					$default
				);
			};
			die "$@ in section '$k'\n" if $@;
			$seen{$k} = 1;
			next;
		} elsif (ref $default eq 'ARRAY') {
			die "cannot handle config_template for '$k'!\n" 
				unless ref $default->[0] eq 'HASH';
			$to->{$k} = [];
			if (exists $from->{$k}) {
				my $i = 0;
				eval {
					die "[ { }, ... ] expected, not '$from->{$k}'\n"
						unless ref $from->{$k} eq 'ARRAY';
					foreach my $h (@{$from->{$k}}) {
						die "[ { }, ... ] expected, not '$h'\n"
							unless ref $h eq 'HASH';
						__hash_assign_with_template(
							$to->{$k}->[$i++]={},
							$h,
							$default->[0]
						);
					}
				};
				die "$@ in $i. argument of list section '$k'\n" if $@;
				$seen{$k} = 1;
				next;
			} else {
				die "list option '$k' missing from argument list!\n";
			}
		}
		$to->{$k} = $from->{$k},
			$seen{$k} = 1, next
			if exists $from->{$k} and defined $from->{$k};
		$to->{$k} = $default, next
			 if defined $default;
		die "option '$k' missing from argument list!\n";
	}
	for my $k (keys %$from) {
		next if $seen{$k};
		die "unknown option '$k' in argument list!\n";
	}
	return 1;
}

sub _init_config {
	my $me = shift;
	my $class = ref $me;
	my $template = $me->_class_data('config_template') || {};
	croak "${class}::ClassData{'config_template'} should be "
	     ."{ attr1 => default_value1, sect1 => { attr => defaul }, ... }!\n"
		unless ref $template eq 'HASH';

	my $c = shift;
	eval { __hash_assign_with_template($me->{_config},$c,$template) };
	croak "$@" if $@;

	return 1;
}

# check whether a given (partial) state matches the current state
sub _compare_states {
	my $me  = shift;
	my $class = ref $me;
	my $state = shift;
	my $status   = $me->{_status};
	my $possible = $me->_class_data('_possible_states');
	my $ret = 1;
	# reset iterator, just in case

	$state = { status => $state } if not ref $state;
	keys %$state;
	while (my ($aspect,$value) = each %$state) {
		croak "no such aspect '$aspect'\n"
			unless exists $status->{$aspect};
		croak "no such state '$value' "
		     ."in ${class}::ClassData{'states'}. Possible typo?\n"
			unless ref $value eq 'Regexp'
			or exists $possible->{$aspect}->{$value};
		# no short circuit return,
		# I want to see the croak above if it applies
		$ret = 0, last
			if not defined $status->{$aspect};
		$ret &&= ref $value eq 'Regexp'
			? $status->{$aspect} =~ $value
			: $status->{$aspect} eq $value;
	}
	# because of the "last" above,
	# reset the HASH iterator, just in case...
	scalar keys %$state;
	return $ret;
}

sub _register_event_methods {
	my $me = shift;
	my $this_class = ref $me;
	my $class_data = $me->_class_data;
	my $events     = $class_data->{events};
	my $states     = $class_data->{states};
	my $possible   = $class_data->{_possible_states} = {};

	$states = { status => $states } if ref $states eq 'ARRAY';
	croak "${this_class}::ClassData{'states'} should be "
	     ."{ aspect => [ qw( possible values) ], ... }!\n"
		unless ref $states eq 'HASH';
	croak "${this_class}::ClassData{'events'} not a HASH ref!\n"
		unless ref $events eq 'HASH';
	while (my ($aspect,$values) = each %$states) {
		for (@$values) { $possible->{$aspect}->{$_} = 0 }
	}
	(my $class = $this_class) =~ s/^[^:]+::([^:]+).*?$/$1/;
	while (my ($event,$state) = each %$events) {
		$class_data->{_statistics}->{events}->{$event} = 0;

		# be nice to myself...
		croak "${this_class}::ClassData{'events'}->{$event} "
		     ."is not a valid (sub)set of status aspects!\n"
			if ref($state) !~ /^$|^HASH$/;

		$state = { status => $state } if not ref $state;
		while (my ($aspect,$value) = each %$state) {
			croak "no such aspect '$aspect' "
			     ."in ${this_class}::ClassData{'states'}. Possible typo?\n"
				unless exists $possible->{$aspect};
			croak "no such state '$value' "
			     ."in ${this_class}::ClassData{'states'}->{$aspect}. Possible typo?\n"
				unless exists $possible->{$aspect}->{$value};
		}

		next if $me->can($event);
		croak "no such method: ${this_class}->$event\n";
	}
}

sub _notify {
	my ($me,$obj,$args,$add_args) = @_;
	my $obj_class = ref $obj;
	my $slots  = $me->_class_data('slots');

	carp "additional arguments ignored, starting from $_[4]!\n"
		if @_ > 4;

	## should never happen...
	## $me->say($obj->id
	##  	. " notifies me about its new status"
	##  	. " (" . $obj->status .  ")"
	##  	. " but no \$ClassData{slots}->{$obj_class} exists!\n"), return
	##  	unless exists $slots->{$obj_class};

	$me->say($obj->id
	  	. " now is " . __dump_hash($obj->status) ) if $::LGE_IS_DEBUGGING;

	$obj_class =~ s/^[^:]+::([^:]+).*?$/$1/;
	my $method = "${obj_class}_changed";

	$me->$method($obj,$args,$add_args);
}

sub _propagate_state_change {
	my ($me,$event) = @_;

	my $CRM = 0;
	foreach my $user
	( sort { $b->[0]->{_refcnt} <=> $a->[0]->{_refcnt}
				||
		 $a->[0]->{_id} cmp $b->[0]->{_id}         }  values %{$me->{_users}}
	) {
		$CRM = $user, next
			if $user->[0]->isa('LGE_CTH::CRM');
		$user->[0]->_notify($me,$user->[1],$event);
	}
	# notify CRM last!
	$CRM->[0]->_notify($me,$CRM->[1],$event) if $CRM;
}

# I don't use %ENV, because this way debugging is easily done
# by using "bash -vxcu instead of bash -c
#sub _env {
#	my $me = shift;
#	my $env = "";
#	for my $k (keys $me->{_config}) {
#		$env .= 
#	}
#}

sub _generic_event {
	my ($me,$event,$new_state,$script) = @_;
	$me->say("I am BUSY! Coding error in CTH..."), return
		if $me->{_busy};

	$me->{_busy} = $event;
	Log("\U$event\E $me->{_id}");
	_spawn( "$me->{_id}->$event", $script,
		sub {
			my $ex = shift;
			$me->{_busy} = 0;
			if (not defined $ex or $ex != 0) {
				$me->say(sprintf "\n.\n\Ucannot $event\E, exit code %d:%d\n", $ex >> 8,$ex & 255);
				# die ?
			} else {
				--$LGE_CTH::FAILED if $event eq 'heal';
				++$LGE_CTH::FAILED if $event eq 'fail';
				$me->status($new_state,$event,'done');
			}
		}
	);
}

# break circular references
# could be DESTROY...
# only needs to be called if one wants to reconfigure the
# "hardware set", so basically never.
#
#
# sub _destroyed {
# 	my ($me,$obj) = @_;
# 	# print "$me->{_id} notified of destruction of $obj->{_id}\n";
# 	delete $me->{_deps}->{$obj->id};
# }

sub _remove_all_references {
	my $me = shift;
	# print "DESTROYing $me->{_id}\n";
	$me->{_users} = undef;
	$me->{_real} = undef;
	while (my ($id,$obj) = each (%{$me->{_deps}})) {
		# print "_unregister $me->{_id} from $id\n";
		next unless defined $obj and ref $obj;
		$obj->_unregister_user($me);
	}
	$me->{_deps} = undef;
}

sub _inc_refcnt {
	my $me = shift;
	$me->{_refcnt}++;
	for my $d (values %{$me->{_deps}}) { $d->_inc_refcnt }
}

# FIXME do I need a _dec_refcnt, too ?

sub _register_user {
	my ($me,$user,$args) = @_;
	$user||='UNDEF';
	croak "$user is not a " . __PACKAGE__ . "!\n"
		unless ref $user and $user->isa(__PACKAGE__);
	
	if (exists $me->{_users}->{$user->id}) {
		carp "$user->{_id} already registered as user of $me->{_id}\n";
		return 0;
	}
	$me->{_users}->{$user->id} = [ $user, $args ];
	$me->_inc_refcnt;
	return 1;
}

sub _unregister_user {
	my ($me,$user) = @_;

	if (not exists $me->{_users}->{$user->id}) {
		carp "$user->{_id} not registered as user of $me->{_id}\n";
		return 0;
	}
	delete $me->{_users}->{$user->id};
	return 1;
}

# helper, not method
sub __dump_hash {
	my $h = shift;
	$h = shift if ref($h) =~ /^LGE_CTH::/;
	my $s = "{ "
		. join(", ",
			map { "'$_' => "
				. (defined $h->{$_} ? "'$h->{$_}'" : 'undef')
			} sort keys %$h )
		. " }";
}

# helper, not method
sub __dump {
	my ($o,$l) = @_;
	my $s = "undef";
	return $s unless defined $o;
	my $indent = "\t" x $l;
	for (ref $o) {
		/^HASH$/ and do {
				return "{ }" if keys(%$o) == 0;
				# return __dump_hash($o)
				#	if keys(%$o) <= 3;
				$s = "{\n";
				my ($k,$v);
				for $k (sort keys %$o)  {
					$v = $o->{$k};
					$s .= "$indent\t'$k' => ".__dump($v,$l+1).",\n";
				}
				$s .= "$indent}";
			}, last;

		/^SCALAR$/ and
			$s = "\($$o)", last;
		/^ARRAY$/  and
			$s = "[@{[join ', ', map { __dump($_,$l+1) } @$o]}]", last;
		/^CODE$/ and
			$s = "$o", last;
		!/^$/ and $o->isa(__PACKAGE__) and
			/^[^:]*::(.*)/,
			$s = "$1=($o->{_id})", last;
		$s = "'$o'";
	}
	# $s =~ s/\n(.)/"\n".("\t" x $l).$1/e;
	return $s;
}

1;
